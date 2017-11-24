
rule m2321_631e96c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.631e96c9cc000b16"
     cluster="m2321.631e96c9cc000b16"
     cluster_size="47"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['032a91aca380744304c874b21552a808','05852d655e5b1dcf4584dd0afae5c043','5323167028c38d8ba8b617780f0e7c4a']"

   strings:
      $hex_string = { 9dcdf71b9c56a669016d4a40544ce30bf18bd6465c57f4fba3268ee0b503357662ba92b63db500718395ac16449877999a9e8379c2d8b4c45be2fa966680a2f6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
