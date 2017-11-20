
rule k3e9_51a933360aab6b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51a933360aab6b32"
     cluster="k3e9.51a933360aab6b32"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['0d4abef599b64e83d19c651670fa31ab','8bba0836f96ab1054df53e14e5fc9dae','e21ecfdaa45058ae20ecf21c5a804994']"

   strings:
      $hex_string = { 0580f97e722e33c0fcaa80fe0175bb80fa0172b62bfc83ff0672af8a04243c4074a83c2e74a454e848ffffffeb9cfec2eb02fec68ac1fcaaeb9453ff564081c4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
