
rule n3ed_4a1ac7e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.4a1ac7e9c8800b12"
     cluster="n3ed.4a1ac7e9c8800b12"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['19d076d7ddc9f67883a2cf0c531278b7','31c69e18a0aeef02537a153edeef3f65','db8e0c68f79d029a32569d8af2d0d2d4']"

   strings:
      $hex_string = { 074b074c074d074e074f0750075107520753075407550756075707580759075a075b075c075d075e075f0760076107620763076407650766076707680769076a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
