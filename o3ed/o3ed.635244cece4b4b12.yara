
rule o3ed_635244cece4b4b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.635244cece4b4b12"
     cluster="o3ed.635244cece4b4b12"
     cluster_size="518"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['00cb96b50807b3f65279372988798cf1','02396e0d3323bc5d234f385bd48075a9','1848b115a3c37c8eb1862c50e422454e']"

   strings:
      $hex_string = { e99a14fcff8d4df0e907d5f3ff8b5424088d420c8b4aec33c8e8bf17fcffb8e0b45453e97714fcff8d4df0e9e4d4f3ff8b5424088d420c8b4aec33c8e89c17fc }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
