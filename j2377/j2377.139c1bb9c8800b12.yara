
rule j2377_139c1bb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2377.139c1bb9c8800b12"
     cluster="j2377.139c1bb9c8800b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery html"
     md5_hashes="['3081a192e9fed0918581a5a247cc73d2','5a837965be987894dec9e68b6469f905','d17fe2ca978e4d60265fb7d306bf2963']"

   strings:
      $hex_string = { 616b6f7a69636b692e7a612e706c2f6a732f6a71756572792e6d696e2e7068703f635f7574743d47393138323526635f75746d3d272b656e636f646555524943 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
