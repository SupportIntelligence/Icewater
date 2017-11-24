
rule m2321_639c16c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.639c16c9cc000b16"
     cluster="m2321.639c16c9cc000b16"
     cluster_size="115"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['01edfcd5487c341eb54d756d5c766e40','0310335a7e20ea74aee7254426abeac6','1ed03e151c96f0b49be56f173de40a3a']"

   strings:
      $hex_string = { 200267e415db49c028e6313effc487b01ceb84e05d2a95f8f71e509913dc722df1a81d25075ca1598fb1bf97d28046d8b20ef20a185412765f1af8c9eae8686d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
