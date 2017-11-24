
rule k2321_092d3922d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.092d3922d9eb1912"
     cluster="k2321.092d3922d9eb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['07059c085bc321d37837943fcd81fc50','d699fec58388dc86523820bafec51bff','dc0865da2723eb1675d50b4b0926b337']"

   strings:
      $hex_string = { f63cec35b063dc023ba6bdd0805a710b2f3f612060984aa0cd806489c2f776554b14beef1b9cb433a7305c70e3d82374fa586dd9aa578e002bc151f4e975561c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
