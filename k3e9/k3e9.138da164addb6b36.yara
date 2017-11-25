
rule k3e9_138da164addb6b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.138da164addb6b36"
     cluster="k3e9.138da164addb6b36"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['5b8c9b2a38f20d909c83854bd7085498','b300685a02d0cd63f1d7357fc9ecfea0','c5b127aad05e9fa676016d62c5d2a636']"

   strings:
      $hex_string = { c9c32e8bc08a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff249540 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
