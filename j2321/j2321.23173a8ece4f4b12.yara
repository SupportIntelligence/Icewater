
rule j2321_23173a8ece4f4b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.23173a8ece4f4b12"
     cluster="j2321.23173a8ece4f4b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader generickd"
     md5_hashes="['56ff9a8e3c454c4f9d201072c9fbe377','6a445fe5f65ccc9301bd66a549a4d29d','b4eea83d7156f742ca0c64a9e91d908a']"

   strings:
      $hex_string = { 507181f3eb7b293b83dc2749bd9537c930e5213c65e1075b324d3dc0b1bc4653335711e6de0ea5d5e439083e1b0fd1902ac168a42b9be1ee094e0eed74a2f10d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
