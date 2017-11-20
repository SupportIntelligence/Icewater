
rule j3e9_23173a8ecebb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.23173a8ecebb0b12"
     cluster="j3e9.23173a8ecebb0b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader generickd"
     md5_hashes="['2b687323f7f8fd894a4507515a1144a1','401fa61dd01287525a8a4cd0a0e30097','7ad98c7de32f2f7231c3c0091dd16771']"

   strings:
      $hex_string = { 507181f3eb7b293b83dc2749bd9537c930e5213c65e1075b324d3dc0b1bc4653335711e6de0ea5d5e439083e1b0fd1902ac168a42b9be1ee094e0eed74a2f10d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
