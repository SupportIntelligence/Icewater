
rule n3fd_0842892c5ba30b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fd.0842892c5ba30b14"
     cluster="n3fd.0842892c5ba30b14"
     cluster_size="326"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo abde"
     md5_hashes="['02b3064f63e45e6828b510e45981e9a7','02dee4afb97b0d4399be246e3eb062f4','0b8f466ec8580f316f466bb51a608c38']"

   strings:
      $hex_string = { 0226070d181183601183641183680e081802091281b9151182e90108151182e90108151182e901080a07041281791284cd0e0e05200012818105200012826d03 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
