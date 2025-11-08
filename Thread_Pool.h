#pragma once

#include<mutex>
#include<thread>
#include<vector>
#include<queue>
#include<functional>
#include<condition_variable>

class ThreadPool {
private:
    std::vector<std::thread> threads;
    std::queue<std::function<void()>> tasks;
    std::mutex mtx;
    std::condition_variable condition;
    bool stop;
public:
    ThreadPool(int numthreads);
    ~ThreadPool();

	template<class F, class...Args>
	void enqueue(F&& f, Args&&...args) {
		std::function<void()> task = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
		{
			std::unique_lock<std::mutex> lock(mtx);
			tasks.emplace(std::move(task));
		}
		condition.notify_one();
	}
};
