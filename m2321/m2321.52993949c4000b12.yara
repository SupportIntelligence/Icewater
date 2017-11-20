
rule m2321_52993949c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.52993949c4000b12"
     cluster="m2321.52993949c4000b12"
     cluster_size="54"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['016abb6a791589b5dfe930b59a483e74','079e42e169fc674671366930a37d80ba','4ec9ba802bbb068b74579ad14f4a35c2']"

   strings:
      $hex_string = { 035d4a04054e83490190e9e38206e515a519c6be11209acf690e615a3f7b3c803d666bfcd9463b71ae438dbccbcd23288176bd7a87c7cae1007799d14f40579c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
