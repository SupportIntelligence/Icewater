
rule k3e9_138da164acc56b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.138da164acc56b32"
     cluster="k3e9.138da164acc56b32"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['a182bdab4c8e69b7bf3773137ae55bd2','a713336b1cf2297ba7bcf367e0d95f46','ebae705a15f88cf7857f14baca624ec8']"

   strings:
      $hex_string = { c9c32e8bc08a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff249540 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
