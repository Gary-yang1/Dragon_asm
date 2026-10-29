import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { triggerTaskRun, type TaskRun, type TaskTemplate } from '../api/discovery';
import { WebBatchRunDialog } from '../pages/discovery/WebBatchRunDialog';

vi.mock('../api/discovery', () => ({ triggerTaskRun: vi.fn() }));
const triggerRun = vi.mocked(triggerTaskRun);

function template(id: number, targetCount = 2, projectId = 5): TaskTemplate {
  return {
    id, project_id: projectId, name: `Web 批次 ${id}`, task_type: 'web_probe', scope_id: 8,
    config: { targets: Array.from({ length: targetCount }, (_, index) => ({ type: 'url', value: `https://host-${id}-${index}.example.com` })), options: {} },
    schedule: '', enabled: true, timeout_seconds: 1800, rate_limit: 10, concurrency: 5, retry_limit: 0
  };
}

function run(templateId: number, projectId = 5): TaskRun {
  return { id: 100 + templateId, project_id: projectId, template_id: templateId, scope_id: 8, task_type: 'web_probe', status: 'pending', progress: 0 };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

beforeEach(() => {
  triggerRun.mockReset();
  triggerRun.mockImplementation(async (projectId, templateId) => run(templateId, projectId));
});

describe('WebBatchRunDialog', () => {
  it('shows target examples and expands the complete batch without starting a task', async () => {
    const batch = { ...template(1, 1000), name: 'web_exposure_baseline:2.0.0:scope=8:hash=internal' };
    render(<WebBatchRunDialog projectId={5} templates={[batch]} onClose={vi.fn()} onSubmitted={vi.fn()} />);
    expect(screen.getByRole('columnheader', { name: '目标示例' })).toBeInTheDocument();
    expect(screen.getByText(batch.config.targets[0].value)).toBeInTheDocument();
    expect(screen.getByText('另 999 个网址')).toBeInTheDocument();
    expect(screen.queryByText(batch.name)).not.toBeInTheDocument();
    expect(screen.queryByLabelText('第 1 批完整 URL 目标')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '查看第 1 批全部目标' }));

    const targetList = screen.getByLabelText('第 1 批完整 URL 目标');
    expect(targetList.textContent?.split('\n')).toEqual(batch.config.targets.map(target => target.value));
    expect(targetList.children).toHaveLength(0);
    expect(targetList).toHaveStyle({ maxHeight: '240px', overflow: 'auto' });
    expect(screen.getByRole('button', { name: '收起第 1 批全部目标' })).toHaveAttribute('aria-expanded', 'true');
    expect(triggerRun).not.toHaveBeenCalled();
  });

  it('only submits after explicit confirmation, then submits every batch in order', async () => {
    const onSubmitted = vi.fn();
    render(<WebBatchRunDialog projectId={5} templates={[template(1, 100), template(2, 100), template(3, 24)]} onClose={vi.fn()} onSubmitted={onSubmitted} />);
    expect(screen.getByText('224')).toBeInTheDocument();
    expect(screen.getByText(/本次操作不会修改授权范围/)).toBeInTheDocument();
    expect(triggerRun).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole('button', { name: '运行全部批次' }));

    await waitFor(() => expect(onSubmitted).toHaveBeenCalledWith([run(1), run(2), run(3)]));
    expect(onSubmitted).toHaveBeenCalledTimes(1);
    expect(triggerRun.mock.calls).toEqual([[5, 1], [5, 2], [5, 3]]);
  });

  it('keeps successful run IDs visible and stops after an uncertain second request', async () => {
    triggerRun.mockResolvedValueOnce(run(1)).mockRejectedValueOnce(new Error('连接中断'));
    const onSubmitted = vi.fn();
    render(<WebBatchRunDialog projectId={5} templates={[template(1), template(2), template(3)]} onClose={vi.fn()} onSubmitted={onSubmitted} />);

    await userEvent.click(screen.getByRole('button', { name: '运行全部批次' }));

    expect(await screen.findByText('已停止提交后续批次')).toBeInTheDocument();
    expect(screen.getByText('已提交 · #101')).toBeInTheDocument();
    expect(screen.getByText(/此批可能已经启动/)).toBeInTheDocument();
    expect(triggerRun.mock.calls).toEqual([[5, 1], [5, 2]]);
    expect(onSubmitted).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: '运行全部批次' })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '查看执行记录' }));
    expect(onSubmitted).toHaveBeenCalledWith([run(1)]);
    expect(onSubmitted).toHaveBeenCalledTimes(1);
    expect(triggerRun).toHaveBeenCalledTimes(2);
  });

  it('guards repeated confirmation clicks and never submits a successful template twice', async () => {
    const first = deferred<TaskRun>();
    triggerRun.mockReturnValueOnce(first.promise);
    const onSubmitted = vi.fn();
    render(<WebBatchRunDialog projectId={5} templates={[template(1), template(1), template(2)]} onClose={vi.fn()} onSubmitted={onSubmitted} />);
    const confirm = screen.getByRole('button', { name: '运行全部批次' });
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    expect(triggerRun).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: /关\s*闭/ })).toBeDisabled();

    await act(async () => { first.resolve(run(1)); });

    await waitFor(() => expect(onSubmitted).toHaveBeenCalledWith([run(1), run(2)]));
    expect(onSubmitted).toHaveBeenCalledTimes(1);
    expect(triggerRun.mock.calls).toEqual([[5, 1], [5, 2]]);
    expect(screen.queryByRole('button', { name: '运行全部批次' })).not.toBeInTheDocument();
  });

  it('stops submitting after the project changes and ignores the old response', async () => {
    const first = deferred<TaskRun>();
    triggerRun.mockReturnValueOnce(first.promise);
    const onSubmitted = vi.fn();
    const { rerender } = render(<WebBatchRunDialog projectId={5} templates={[template(1), template(2)]} onClose={vi.fn()} onSubmitted={onSubmitted} />);
    await userEvent.click(screen.getByRole('button', { name: '运行全部批次' }));

    rerender(<WebBatchRunDialog projectId={6} templates={[template(3, 2, 6)]} onClose={vi.fn()} onSubmitted={onSubmitted} />);
    await act(async () => { first.resolve(run(1)); });

    expect(triggerRun.mock.calls).toEqual([[5, 1]]);
    expect(onSubmitted).not.toHaveBeenCalled();
    expect(screen.queryByText('已提交 · #101')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '运行全部批次' })).toBeEnabled();
  });

  it('does not submit later batches after unmounting', async () => {
    const first = deferred<TaskRun>();
    triggerRun.mockReturnValueOnce(first.promise);
    const onSubmitted = vi.fn();
    const { unmount } = render(<WebBatchRunDialog projectId={5} templates={[template(1), template(2)]} onClose={vi.fn()} onSubmitted={onSubmitted} />);
    await userEvent.click(screen.getByRole('button', { name: '运行全部批次' }));
    unmount();
    await act(async () => { first.resolve(run(1)); });
    expect(triggerRun.mock.calls).toEqual([[5, 1]]);
    expect(onSubmitted).not.toHaveBeenCalled();
  });

  it('offers execution records even if the first request has an uncertain result', async () => {
    triggerRun.mockRejectedValueOnce(new Error('连接中断'));
    const onSubmitted = vi.fn();
    render(<WebBatchRunDialog projectId={5} templates={[template(1), template(2)]} onClose={vi.fn()} onSubmitted={onSubmitted} />);
    await userEvent.click(screen.getByRole('button', { name: '运行全部批次' }));
    await userEvent.click(await screen.findByRole('button', { name: '查看执行记录' }));
    expect(onSubmitted).toHaveBeenCalledWith([]);
    expect(onSubmitted).toHaveBeenCalledTimes(1);
    expect(triggerRun).toHaveBeenCalledTimes(1);
  });

  it('does not open or send requests when there is no selected batch', () => {
    render(<WebBatchRunDialog projectId={5} templates={null} onClose={vi.fn()} onSubmitted={vi.fn()} />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(triggerRun).not.toHaveBeenCalled();
  });
});
