
rule n26bb_712951928e666d32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.712951928e666d32"
     cluster="n26bb.712951928e666d32"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dangerousobject multi backdoor"
     md5_hashes="['e421ef6c8ef8731c86c1074f9de19008dcf7a05d','d3d27abd4252bd6526bb1a14d428630695e42560','17b953c6e775dc004bed792eb157bfc933ab058d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.712951928e666d32"

   strings:
      $hex_string = { 028b86569ad11fccc8f56b718314a1aea6aa643cac5220f30f12b59b135b59b989461d9c8c27d406a562ddbd7ada17c2981ee52572ca8e42b8047e5e90c14c85 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
