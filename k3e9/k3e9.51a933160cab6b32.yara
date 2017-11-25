
rule k3e9_51a933160cab6b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51a933160cab6b32"
     cluster="k3e9.51a933160cab6b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['11b812546b53d5f5d185522afc723f84','ac859bfa04052984576556cecb960da5','b78ed0c32661c63c769d871b0f397106']"

   strings:
      $hex_string = { 80f97e722e33c0fcaa80fe0175bb80fa0172b62bfc83ff0672af8a04243c4074a83c2e74a454e848ffffffeb9cfec2eb02fec68ac1fcaaeb9453ff564081c400 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
