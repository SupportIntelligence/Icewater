
rule n3ed_1b2fab05c6230b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b2fab05c6230b12"
     cluster="n3ed.1b2fab05c6230b12"
     cluster_size="22"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['0b1d94c7a50820f561f9d3db99b0c6f0','21ceefe47fe8741f794f9db03f378388','f2f439a81fa403535f0de56c8b01dbbd']"

   strings:
      $hex_string = { 3c3075040bc9eb022bc88d45d050ff75145157e80865000083c4103bc37404881eeb588b45d4483945e00f9cc183f8fc7c2d3b45147d283acb740a8a074784c0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
