
rule n231d_0b199299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.0b199299c2200b12"
     cluster="n231d.0b199299c2200b12"
     cluster_size="66"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hqwar bankbot"
     md5_hashes="['e1fbc9a7d35e0eedd9506391873634bd65907aa6','25d6491f732f4132765213a36922be9a67ca4687','8860b08892ed55ae2b6e0f3bc86acbf35c1b754a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.0b199299c2200b12"

   strings:
      $hex_string = { 6f5b8aca6274fa833be4bf2032694c3e7ddb9c85578e4ff6bc1d1792512b61dae6dffcf75524e7b7f4d8eb28c4d5387b07d1c6e3b9b033d664fdcfecac301318 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
