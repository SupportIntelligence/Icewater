
rule m3e9_13635cc344000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13635cc344000916"
     cluster="m3e9.13635cc344000916"
     cluster_size="1287"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted cloud"
     md5_hashes="['00625fc4d727d21e1b9d03b8188c4264','0084bcfe773ad4f46f7026f5465b5818','03f43216bb02bf1e44610ddfc257599f']"

   strings:
      $hex_string = { b32b489c062289e24c099e97af52369e01623a218130a25bb6c23e37c8b10c9fd93557d8cdd723d22a593c511c0bc9fc466d18329419439160f10fea026a1454 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
