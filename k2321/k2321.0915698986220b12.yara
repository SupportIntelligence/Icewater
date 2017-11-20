
rule k2321_0915698986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0915698986220b12"
     cluster="k2321.0915698986220b12"
     cluster_size="5"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['0ddbd8f08842ce3f0fc2bccbdd30d8c3','25759b0b75eacd4ad482fdc408d3b0fe','fd171ef08b30b03dfcd247a72c10e785']"

   strings:
      $hex_string = { d4e1d73a7dd61887312db1017e1e3334dadce0307f04bac349702f14cea3eeafbe35af115d7b4765f7d32199570ed91ce95b42278f81c783ca85022eb7a54cd1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
