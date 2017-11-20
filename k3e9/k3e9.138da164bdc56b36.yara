
rule k3e9_138da164bdc56b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.138da164bdc56b36"
     cluster="k3e9.138da164bdc56b36"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['58c1e768d01d9263dd471f80b6c27021','9a3f26eb3381ca49d96b99bd134b08a0','dbeba63fb0892e1ba63e4bcf30ceb989']"

   strings:
      $hex_string = { c9c32e8bc08a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff249540 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
