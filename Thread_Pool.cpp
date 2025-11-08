#include "Thread_Pool.h"


ThreadPool::ThreadPool(int numthreads):stop(false) {
		for (int i = 0; i < numthreads; i++) {
			threads.emplace_back([this] {
				while (1) {
					std::unique_lock<std::mutex> lock(mtx);
					condition.wait(lock, [this] {
						return !tasks.empty() || stop;
						});

					if (tasks.empty() && stop) {
						return;
					}

					std::function<void()> task = std::move(tasks.front());
					tasks.pop();
					lock.unlock();
					task();
				}
				});
		}
	}

ThreadPool::~ThreadPool() {
		{
			std::unique_lock<std::mutex> lock(mtx);
			stop = true;
		}
		condition.notify_all();
		for (std::thread& work : threads) {
			work.join();
		}
	}

