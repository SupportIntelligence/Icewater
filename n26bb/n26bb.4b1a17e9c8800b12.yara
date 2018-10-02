
rule n26bb_4b1a17e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4b1a17e9c8800b12"
     cluster="n26bb.4b1a17e9c8800b12"
     cluster_size="40"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious classic dealply"
     md5_hashes="['844fceff2b1d684b68c72a9cf78b9ca0bd318100','5c80f8dfacf5d3cca8f98472404cb257c86525ba','ba07e289daf65738cf4d2c9798f4564c2b574c4e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4b1a17e9c8800b12"

   strings:
      $hex_string = { c7830a4f43c4c153cff6aebc2a07696573d59e2014074c3b74d8544dfccc64248fe4ba81a982da32841f0460d7155d44ea617db07601c3ecb177201c1f2fac15 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
