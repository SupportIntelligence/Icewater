
rule o3ed_635244cece4b9b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.635244cece4b9b12"
     cluster="o3ed.635244cece4b9b12"
     cluster_size="2257"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['00a398133b41834f3d4d917165d5c86c','00cfe50bd5c17109f8016bc2993e9852','043a357051e748c8ce414632ce3a9ae1']"

   strings:
      $hex_string = { e99a14fcff8d4df0e907d5f3ff8b5424088d420c8b4aec33c8e8bf17fcffb8e0b45453e97714fcff8d4df0e9e4d4f3ff8b5424088d420c8b4aec33c8e89c17fc }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
