package com.alibou.app.todo;

import com.alibou.app.category.response.CategoryResponse;
import com.alibou.app.todo.request.TodoRequest;
import com.alibou.app.todo.request.TodoUpdateRequest;
import com.alibou.app.todo.response.TodoResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

@Service
public class TodoMapper {
    public Todo toTodo(final TodoRequest request) {
        return Todo.builder()
                   .title(request.getTitle())
                   .description(request.getDescription())
                   .startDate(request.getStartDate())
                   .endDate(request.getEndDate())
                   .startTime(request.getStartTime())
                   .endTime(request.getEndTime())
                   .done(false)
                   .build();
    }

    public void mergerTodo(final Todo todoToUpdate, final TodoUpdateRequest request) {
        if (StringUtils.isNotBlank(request.getTitle())
                && !todoToUpdate.getTitle()
                                .equals(request.getTitle())) {
            todoToUpdate.setTitle(request.getTitle());
        }
        if (StringUtils.isNotBlank(request.getDescription())
                && !todoToUpdate.getDescription()
                                .equals(request.getDescription())) {
            todoToUpdate.setDescription(request.getDescription());
        }
    }

    public TodoResponse toTodoResponse(final Todo todo) {
        return TodoResponse.builder()
                           .id(todo.getId())
                           .title(todo.getTitle())
                           .description(todo.getDescription())
                           .startDate(todo.getStartDate())
                           .endDate(todo.getEndDate())
                           .startTime(todo.getStartTime())
                           .endTime(todo.getEndTime())
                           .done(todo.isDone())
                           .category(
                                   CategoryResponse.builder()
                                                   .name(todo.getCategory()
                                                             .getName())
                                                   .description(todo.getCategory()
                                                                    .getDescription())
                                                   .build()
                           )
                           .build();
    }
}
