
rule o3e9_157308469692799a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.157308469692799a"
     cluster="o3e9.157308469692799a"
     cluster_size="2217"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['000590510cf1d6efd7119a9ac8c3b895','000fe8f959c8ff71efb27f8e5ad2b0a5','01f76e9a67c4a6875c78756f125d227d']"

   strings:
      $hex_string = { 831e4667358453282d1e67e1936b10cdb16d917198ab4f35b3e3f929a95c647d0a7a3ed1dd3c54a9f22bd2c8f4b8c134e5798258681ddeb1fd02860f1feacc19 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
