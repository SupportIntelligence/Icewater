
rule n3e9_299d154bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.299d154bc6220b12"
     cluster="n3e9.299d154bc6220b12"
     cluster_size="48"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['2c785192a602551a26b8f46ca68cb5ac','4167240e3fcecc9611bd9603c5ea0ecc','ada49e8e0a42102e73b91731698064a3']"

   strings:
      $hex_string = { 0de9629fdc294b78c54715811ba94090c5cffcf50ad6d9b6fc4f28c88407b1fa040fbde951a0a49b199f7f70a9855e81bee8ea8034eb053d43c347bfc54561f9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
