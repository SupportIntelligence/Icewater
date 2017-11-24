
rule k3e9_1b1b194ad89b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1b194ad89b0912"
     cluster="k3e9.1b1b194ad89b0912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt injector symmi"
     md5_hashes="['02df15de5bdd5e9be466c89ce755d0a8','4e16d9171d257a348261805afcb004f3','feff7ec8fa0bae9eddcad4cdbfea01e8']"

   strings:
      $hex_string = { 1f95d125e2c62f3a9455de4f79fd82bdaf173cb2455cc436edb1610e7b74e7ae585fc2aaa15afb99e3f05bc7411503da35539e32725d9f12b8a76a8a8d628f34 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
