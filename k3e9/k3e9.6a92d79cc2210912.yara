
rule k3e9_6a92d79cc2210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a92d79cc2210912"
     cluster="k3e9.6a92d79cc2210912"
     cluster_size="5875"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bundler jatif addrop"
     md5_hashes="['0002e2597a1bdbf3ba700af17f4358c4','00067ef2d4288932e5376eccc5cbfecb','00e90d4d37d6f4a42fdee0a81042d036']"

   strings:
      $hex_string = { 81c14156d4cc9f97b5844775778b2d3b9bad210f7c603d094e89e6926fa35e684418680c76e274ac35553cebf5711134e1dac8231c50558c140116248688e590 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
