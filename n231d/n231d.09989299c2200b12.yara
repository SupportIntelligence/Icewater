
rule n231d_09989299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.09989299c2200b12"
     cluster="n231d.09989299c2200b12"
     cluster_size="95"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos hqwar"
     md5_hashes="['f543e7b7d4ca56dc71d8072bd158c29ce697d6ee','2b3c743a0a2b855e1c26c185d2c45e8080f08ddd','09f215d9e5d8acfe7b9e1fb4a3ca86525d155b11']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.09989299c2200b12"

   strings:
      $hex_string = { e91656a93d3c35c73b2fff0baac10eb4d61833dc37b5af522745a14a967f5dc9d46253cb573f9ef099df702c3e0ffeccfa93693621c084a042b8efcfe1b3bf6b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
