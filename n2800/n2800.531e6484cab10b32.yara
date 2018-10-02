
rule n2800_531e6484cab10b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2800.531e6484cab10b32"
     cluster="n2800.531e6484cab10b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mikey neoreklami malicious"
     md5_hashes="['3b08e1936a7f888c0c4f27d012d29b7db7ac3709','f210bd450723ef2ba85444a4c7eaae030a3f85dc','ef1a038a4e8496e66ba9bded13af270605c33800']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2800.531e6484cab10b32"

   strings:
      $hex_string = { bc83f8020f8c7dfeffffc645b0008a45b084c0740833c9ff154eec06008bc723c603c02bf88d043e488b4df04833cce8afb805004c8d5c2470498b5b10498b73 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
