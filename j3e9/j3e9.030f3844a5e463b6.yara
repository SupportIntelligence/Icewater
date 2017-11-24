
rule j3e9_030f3844a5e463b6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.030f3844a5e463b6"
     cluster="j3e9.030f3844a5e463b6"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakeav kazy apdg"
     md5_hashes="['26fd603f3db7df96c491fd158ad3d045','7e10eb7effbbaaad4c8786d36a8154c0','dca7cc648f5edf5c36cbabe4b3eca379']"

   strings:
      $hex_string = { 364b191aeb5618b99c74cb73a671213e85875dda35aa611baf07fc297c9e80178f9acce642372267b7bce276ded968cf8afe234cb8fd4353888e2b445c571dac }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
