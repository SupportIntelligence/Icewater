
rule k3e9_15e10d961ee30132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e10d961ee30132"
     cluster="k3e9.15e10d961ee30132"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['a56d994e6c7e1786e86e6408661d23e9','ae093f5f100775b5309c7db538e5b64f','b6cc287894bbf380e2016e8e4b1ec889']"

   strings:
      $hex_string = { 8082ccc87777777800867c687044447800867f7870ccc4780087f7b8b0bcc478008fffc8bb0000780087f7bbfbb7777800087f22bb8888880008f76bb2b22220 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
