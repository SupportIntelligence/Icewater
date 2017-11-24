
rule k3e9_51a93316098b6b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51a93316098b6b32"
     cluster="k3e9.51a93316098b6b32"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['57ec644255f6874f83bcd3ae4e1f244c','6062ea4c3de0f1da442382c303168665','fe671aec5da3e93522ff8e8dc199d584']"

   strings:
      $hex_string = { 80f97e722e33c0fcaa80fe0175bb80fa0172b62bfc83ff0672af8a04243c4074a83c2e74a454e848ffffffeb9cfec2eb02fec68ac1fcaaeb9453ff564081c400 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
