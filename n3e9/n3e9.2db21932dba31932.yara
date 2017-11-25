
rule n3e9_2db21932dba31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2db21932dba31932"
     cluster="n3e9.2db21932dba31932"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['4b2fc05ce9c59cd622c6c665af3fb0c0','97fd9887a3226c6d39fbf52254476427','e05ee7414220f63937ce9908fca4d691']"

   strings:
      $hex_string = { 0909181818020205050502050509090909081818021d1d1d1d1d1d1d1d1d1d1d01010101011111111111111515141316141413161415151515151515151b1c01 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
