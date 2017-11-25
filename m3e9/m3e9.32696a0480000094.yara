
rule m3e9_32696a0480000094
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.32696a0480000094"
     cluster="m3e9.32696a0480000094"
     cluster_size="64"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce email"
     md5_hashes="['092acd28fe669f6af24f52f8986ded9e','155b7f8fd1aa47face66e4dccd5ea0c4','aa10f7751870722ebf515a58dd02e968']"

   strings:
      $hex_string = { 0580f97e722e33c0fcaa80fe0175bb80fa0172b62bfc83ff0672af8a04243c4074a83c2e74a454e848ffffffeb9cfec2eb02fec68ac1fcaaeb9453ff564081c4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
