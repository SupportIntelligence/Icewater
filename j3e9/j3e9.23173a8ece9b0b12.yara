
rule j3e9_23173a8ece9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.23173a8ece9b0b12"
     cluster="j3e9.23173a8ece9b0b12"
     cluster_size="3"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre generickd trojandownloader"
     md5_hashes="['0a975893e5d5309a18d487b32f7e235e','345248e92f765382f25d4a8cb68a4fb7','ff27aba66d64716ce5923a9d9d31315c']"

   strings:
      $hex_string = { 507181f3eb7b293b83dc2749bd9537c930e5213c65e1075b324d3dc0b1bc4653335711e6de0ea5d5e439083e1b0fd1902ac168a42b9be1ee094e0eed74a2f10d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
