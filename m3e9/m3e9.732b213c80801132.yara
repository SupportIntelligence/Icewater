
rule m3e9_732b213c80801132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.732b213c80801132"
     cluster="m3e9.732b213c80801132"
     cluster_size="108"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut zusy shodi"
     md5_hashes="['01624019825f922d76782e28ce9b52a3','03a5745fd5a44b2264b166da34df0979','26e6d234909dcb9b85b53115e82a8fc7']"

   strings:
      $hex_string = { 522957e36bd63455c00d8e4b9408f7446ac7b3e54cd99fe7af108c35f3e9a77f1df5eab25e052337f860e49a1558a84e635967537c11763bdeadf1c250b60341 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
