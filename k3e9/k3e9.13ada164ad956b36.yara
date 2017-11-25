
rule k3e9_13ada164ad956b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13ada164ad956b36"
     cluster="k3e9.13ada164ad956b36"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['15b46a9357b5717ff579ec46bb430e13','3d714287abbcf36b33f98dbbb2542d23','c1a0e77b29c6d8bafd2e3fb96aa89ea4']"

   strings:
      $hex_string = { c9c32e8bc08a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff249540 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
