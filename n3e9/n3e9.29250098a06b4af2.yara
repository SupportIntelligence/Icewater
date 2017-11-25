
rule n3e9_29250098a06b4af2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29250098a06b4af2"
     cluster="n3e9.29250098a06b4af2"
     cluster_size="631"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy aeed delf"
     md5_hashes="['00ed035489667121bdd03615ef515ff5','0178b424a84a5ef1dcd1eaac935393a3','0c823efcef34ca66dbee5c1c74d5a48a']"

   strings:
      $hex_string = { 36de25072f794d1df1d38b7ea3c6ef0c3906af01cfb4c5659b3258d4b2bf805b5c5e13dbc0fbb5ed1a31ecd864b94697563c7b02aeee60f9d59e87572392fe9d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
