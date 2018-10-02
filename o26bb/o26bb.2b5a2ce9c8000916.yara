
rule o26bb_2b5a2ce9c8000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.2b5a2ce9c8000916"
     cluster="o26bb.2b5a2ce9c8000916"
     cluster_size="207"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu filetour dangerousobject"
     md5_hashes="['192fa4f791ac35726a1adf2916ebf318dbbb219d','89901f7b3f3cf85f9d804e88c1d0bfa2a2126afd','11f47e15d4f3f9c71b9cef87f024129f8f857e88']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.2b5a2ce9c8000916"

   strings:
      $hex_string = { 7b7bb7ff010166ff020264ff100e42ff343028ff322e2aff312d29ff322f2bff6d615cff8e7e78ff8a7b75ff897a74ff867771ff857670ff7c6f69c80000001c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
