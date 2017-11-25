
rule m3e9_36390c8b48000b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.36390c8b48000b10"
     cluster="m3e9.36390c8b48000b10"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir virut runouce"
     md5_hashes="['cb53e105022bd240560fd9e815f2c4f5','d6b4225cd45e9a4848107ad4bedf669e','dbc9abfeb6bc3280c9defc9726554914']"

   strings:
      $hex_string = { 0580f97e722e33c0fcaa80fe0175bb80fa0172b62bfc83ff0672af8a04243c4074a83c2e74a454e848ffffffeb9cfec2eb02fec68ac1fcaaeb9453ff564081c4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
