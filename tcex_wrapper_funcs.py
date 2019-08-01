class threatconnect:
  self.type_mapping = {
      'Host': 'hosts',
      'File': 'files',
      'Address': 'addresses',
      'URL': 'urls',
      'EmailAddress': 'emailAddresses',
      'Adversary': 'adveraries',
      'Campaign': 'campaigns',
      'Document': 'documents',
      'Email': 'emails',
      'Incident': 'incidents',
      'Threat': 'threats',
      'Signature': 'signatures'
  }


  def get_attributes(self, object_type,         self.type_mapping = {
              'Host': 'hosts',
              'File': 'files',
              'Address': 'addresses',
              'URL': 'urls',
              'EmailAddress': 'emailAddresses',
              'Adversary': 'adveraries',
              'Campaign': 'campaigns',
              'Document': 'documents',
              'Email': 'emails',
              'Incident': 'incidents',
              'Threat': 'threats',
              'Signature': 'signatures'
          }object_id):
      object_resource = self.tcex.resource(object_type)
      object_resource.owner = self.owner
      object_resource.resource_id(object_id)
      attribute_resource = object_resource.attributes()
      attribute_response = attribute_resource.request()
      if attribute_response.get('status', 'Failure') == 'Failure':
          self.tcex.exit(
              1,
              'Something went wrong attempting to fetch the attributes\
              for {resource_type} {resource_id}'.format(
                  resource_type=object_type,
                  resource_id=object_id
              )
          )
      return attribute_response.get('data', list())

  def get_tags(self, object_type, object_id):
      object_resource = self.tcex.resource(object_type)
      object_resource.owner = self.owner
      object_resource.resource_id(object_id)
      tag_resource = object_resource.tags()
      results = tag_resource.request()
      if results.get('status', 'Failure') == 'Failure':
          self.tcex.exit(
              1,
              'Something went wrong attempting to fetch tags\
              for {resource_type} {resource_id}'.format(
                  resource_type=object_type,
                  resource_id=object_id
              )
          )
      return results.get('data', list())

  def get_objects_by_filter(self, object_type, filter_type, filter_operation, filter_value):
      object_resource = self.tcex.resource(object_type)
      object_resource.owner = self.owner
      object_resource.add_filter(filter_type, filter_operation, filter_value)
      object_resource.add_payload('includeTags', 'true')
      object_resource.add_payload('includeAttributes', 'true')
      results = object_resource.request()
      if results.get('status', 'Failure') == 'Failure':
          self.tcex.exit(
              1,
              'Something went wrong attempting to fetch object\
              for {resource_type} {resource_name}'.format(
                  resource_type=object_type,
                  resource_name=filter_value
              )
          )
      return results.get('data', list())

  def create_object(self, object_type, object_name):
      # works for threats, other groups may need additional data
      object_resource = self.tcex.resource(object_type)
      object_resource.owner = self.owner
      object_resource.http_method = 'POST'
      object_data = {'name': object_name}
      object_resource.body = json.dumps(object_data)
      results = object_resource.request()
      if results.get('status', 'Failure') == 'Failure':
          self.tcex.exit(
              1,
              'Something went wrong attempting create object\
              for {resource_type} {resource_name}'.format(
                  resource_type=object_type,
                  resource_name=object_name
              )
          )
      return results.get('data', dict())

  def add_tag(self, object_type, object_id, tag):
      object_resource = self.tcex.resource(object_type)
      object_resource.resource_id(object_id)
      object_resource.owner = self.owner
      tag_resource = object_resource.tags(tag)
      tag_resource.http_method = 'POST'
      results = tag_resource.request()
      if results.get('status', 'Failure') == 'Failure':
          self.tcex.exit(
              1,
              'Something went wrong attempting to create tag \
              {tag} for {resource_type} {resource_name}'.format(
                  tag=tag,
                  resource_type=object_type,
                  resource_name=object_id
              )
          )
      return results.get('data', dict())

  def add_attribute(self, object_type, object_id, attribute_type, attribute_value):
      object_resource = self.tcex.resource(object_type)
      object_resource.owner = self.owner
      object_resource.resource_id(object_id)
      attribute_resource = object_resource.attributes()
      attribute_resource.body = json.dumps({
          'type': attribute_type,
          'value': attribute_value
      })
      attribute_resource.http_method = 'POST'
      results = attribute_resource.request()
      if results.get('status', 'Failure') == 'Failure':
          self.tcex.exit(
              1,
              'Something went wrong attempting to create attribute \
              {attribute_type} {attribute_value} for {resource_type} {resource_name}'.format(
                  attribute_type=attribute_type,
                  attribute_value=attribute_value,
                  resource_type=object_type,
                  resource_name=object_id
              )
          )
      return results.get('data', dict())

  def add_association(self, first_object_type, first_object_id, second_object_type, second_object_id):
      object_resource = self.tcex.resource(first_object_type)
      object_resource.owner = self.owner
      if first_object_type in list(self.type_mapping.keys())[5:]:
          first_type = 'groups'
      else:
          first_type = 'indicators'
      path_a = '{}/{}'.format(first_type, self.type_mapping[first_object_type])
      if second_object_type in list(self.type_mapping.keys())[5:]:
          second_type = 'groups'
      else:
          second_type = 'indicators'
      path_b = '{}/{}'.format(second_type, self.type_mapping[second_object_type])
      object_resource._request_uri = '{part_a}/{first_object_id}/{part_b}/{second_object_id}'.format(
          part_a=path_a,
          first_object_id=first_object_id,
          part_b=path_b,
          second_object_id=second_object_id
      )
      object_resource.http_method = 'POST'
      results = object_resource.request()
      if results.get('status', 'Failure') == 'Failure':
          self.tcex.exit(
              1,
              'Something went wrong attempting to create association \
              {first_object_type} {first_object_id} to {second_object_type} {second_object_id}'.format(
                  first_object_type=first_object_type,
                  first_object_id=first_object_id,
                  second_object_type=second_object_type,
                  second_object_id=second_object_id
              )
          )
      return results.get('data', dict())

  def add_rating_and_confidence(self, object_type, object_id, rating, confidence):
      object_resource = self.tcex.resource(object_type)
      object_resource.resource_id(object_id)
      object_resource.owner = self.owner
      object_resource.body = json.dumps(
          {
              'rating': rating,
              'confidence': confidence
          }
      )
      object_resource.http_method = 'PUT'
      results = object_resource.request()
      if results.get('status', 'Failure') == 'Failure':
          self.tcex.exit(
              1,
              'Something went wrong attempting to create rating and confidence for \
              {object_type} {object_id}'.format(
                  object_type=object_type,
                  object_id=object_id
              )
          )
      return results.get('data', dict())

  def get_associations(self, first_object_type, object_id, associations_type, custom_association=None):
      object_resource = self.tcex.resource(first_object_type)
      object_resource.owner = self.owner
      object_resource.resource_id(object_id)
      object_association_resource = self.tcex.resource(associations_type)
      if custom_association:
          associations_resource = object_resource.association_custom(custom_association, association_resource=object_association_resource)
      else:
          associations_resource = object_resource.associations(object_association_resource)
      associations_resource.add_payload('resultLimit', 10000)
      associations_resource.add_payload('includeTags', 'true')
      associations_resource.add_payload('includeAttributes', 'true')
      results = associations_resource.request()
      if results.get('status', 'Failure') == 'Failure':
          self.tcex.exit(
              1,
              'Something went wrong attempting to get associations of type {associations_type} for \
              {object_type} {object_id}'.format(
                  associations_type=associations_type,
                  object_type=first_object_type,
                  object_id=object_id
              )
          )
      return results.get('data', list())
