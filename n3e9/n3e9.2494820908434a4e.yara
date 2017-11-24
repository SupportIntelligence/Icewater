
rule n3e9_2494820908434a4e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2494820908434a4e"
     cluster="n3e9.2494820908434a4e"
     cluster_size="135"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy delf babee"
     md5_hashes="['0896af3d43fd59c4a7d119d42662b746','0a0923be929c690aa0a0aa2347b13bb4','6a50d0294b92bbec2a2751d9dff43447']"

   strings:
      $hex_string = { 93741c8ab1045f54a8e5fc6cb42b98fe76ebde3964c9bd3d6242d0a57fc0f98512df776d5c47f3d86175009910682f3af14ed7a7cc558c3fb30b580e5d26bcd3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
