package com.alibou.app.category.impl;

import com.alibou.app.category.Category;
import com.alibou.app.category.request.CategoryRequest;
import com.alibou.app.category.request.CategoryUpdateRequest;
import com.alibou.app.category.response.CategoryResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

@Service
public class CategoryMapper {
    public Category toCategory(final CategoryRequest request) {
        return Category.builder()
                       .name(request.getName())
                       .description(request.getDescription())
                       .build();
    }

    public void mergeCategory(final Category categoryToUpdate, final CategoryUpdateRequest request) {
        if (StringUtils.isNotBlank(request.getName())
                && !categoryToUpdate.getName()
                                    .equals(request.getName())) {
            categoryToUpdate.setName(request.getName());
        }
        if (StringUtils.isNotBlank(request.getDescription())
                && !categoryToUpdate.getDescription()
                                    .equals(request.getDescription())) {
            categoryToUpdate.setDescription(request.getDescription());
        }
    }

    public CategoryResponse toCategoryResponse(final Category category) {
        return CategoryResponse.builder()
                               .name(category.getName())
                               .description(category.getDescription())
                               .todoCount(category.getTodos()
                                                  .size())
                               .build();
    }
}
