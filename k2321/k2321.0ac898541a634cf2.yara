
rule k2321_0ac898541a634cf2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ac898541a634cf2"
     cluster="k2321.0ac898541a634cf2"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['084e294f50faede0efa9821e93526b0d','4ce0a43c460201f7ee14082df7fa477f','cd88477c6430942ea738d35adc0f2d26']"

   strings:
      $hex_string = { b62b3930a2a6ffa85ca976ab14da7948e6567303b828a19c3146d0906c65aff1e102252112ef1028a01ff0d704c554bfaa8c273ae217b2fa3bf96ef747f2bd2e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
