
rule n3e9_0b150018a04a48f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b150018a04a48f2"
     cluster="n3e9.0b150018a04a48f2"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy aeed xihet"
     md5_hashes="['03c4aa87b8570dc8fb833329db57bbd0','c71f30a9590dbdd10b6c3d46221ca575','e16feae8bc88ff6e0d0cb03c4b47c640']"

   strings:
      $hex_string = { 36de25072f794d1df1d38b7ea3c6ef0c3906af01cfb4c5659b3258d4b2bf805b5c5e13dbc0fbb5ed1a31ecd864b94697563c7b02aeee60f9d59e87572392fe9d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
