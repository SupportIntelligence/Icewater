
rule m3e9_3161395b9ae31112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3161395b9ae31112"
     cluster="m3e9.3161395b9ae31112"
     cluster_size="111"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['0017ff836f30ffa3bad3774c39742b73','04fd288224ed084033c6ad99af2b4230','7ded9d22e07f2b8af478e5034108f3cc']"

   strings:
      $hex_string = { b72aef55dad76cdd36edebb80ee375ce89eb5b686281e00021b6065832e1b50adc2eec574177e2f3859d7e8df40ad43b98f2a3cd0f9f01357897c26449e59330 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
