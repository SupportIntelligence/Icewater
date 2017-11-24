
rule k41a_29993a4f42820912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k41a.29993a4f42820912"
     cluster="k41a.29993a4f42820912"
     cluster_size="4517"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="swiftbrowse browsefox netfilter"
     md5_hashes="['000c34ed342ee2aa3ae81bccad3fab62','00125886570b86d40c829cdf252a8eae','0120c3709888cd143f95370ffbbf9ba5']"

   strings:
      $hex_string = { 152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d07 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
