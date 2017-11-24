
rule m3e9_291a92b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.291a92b9c2200b12"
     cluster="m3e9.291a92b9c2200b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="boht brresmon umbald"
     md5_hashes="['0a8209e119993ca1c7c643a2305600ce','3a129ade79c421b8d2d212383fa3c20c','d950c0a8f8324489485c722f26af795d']"

   strings:
      $hex_string = { 1eb03a7bbf866b9381e2bec0638dd2906cd7574b1613bcd63266643c777867d46e69a9b8d923a5e6c7c210e5ecbaa65d54089d75b6395f47279bab42e3fe749a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
