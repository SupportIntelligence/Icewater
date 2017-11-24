
rule k2321_09655923d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09655923d9eb1912"
     cluster="k2321.09655923d9eb1912"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['02fd575d5f9a46155c43306e7abe21d2','5c938ae9aed1a16af7a4d0b96e179522','d7105c597edc3ece8292d3f7a82887da']"

   strings:
      $hex_string = { e50c5f7417d2271b6cf584de9fe4ec2eb5628906cfc7bf381e6178ea47247d739eeddf8ced5fdc8ffd5af6b650c8f7cc349a533743354dd9c90aa53292058b48 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
