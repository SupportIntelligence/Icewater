
rule n3e9_163144a271064a9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.163144a271064a9a"
     cluster="n3e9.163144a271064a9a"
     cluster_size="817"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softpulse bundler riskware"
     md5_hashes="['00d7c2e5fc7a26d107bd92e56bdab83f','013d46592c7c137700554c1c7cf4f07d','05a958e97c5f14b6aaf2ac326fed5a11']"

   strings:
      $hex_string = { e6eeb75b7263cb35204352d9bac2a3a066305968144479fa9bb1ac275d7b8441ab4c8a26536fef6406c6a288bd780f7e2476ade74d364697d06ddc56e3776949 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
